package goauth

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"uuid"

	"gorm.io/gorm"
)

const (
	// ipAccessTableSuffix follows Config.TablePrefix in the default name
	// (goauth_ip_access_rules).
	ipAccessTableSuffix  = "ip_access_rules"
	defaultIPAccessCache = 30 * time.Second

	ipListWhitelist = "whitelist"
	ipListBlacklist = "blacklist"

	codeIPForbidden = "IP_FORBIDDEN"
	msgIPForbidden  = "Access from this network address is not allowed."
)

// IPAccessOptions configures IP whitelist / blacklist enforcement for the
// goauth HTTP handler. Off by default. When Enabled, MigrateIPAccess creates
// the rules table. Blacklist always denies; a non-empty enabled whitelist
// restricts access to matching addresses only.
type IPAccessOptions struct {
	Enabled bool
	// TableName is the GORM table for IPEntry rows, used as is. Default
	// Config.TablePrefix + "ip_access_rules" ("goauth_ip_access_rules").
	TableName string
	// CacheTTL is how long the enabled rules are kept in memory between
	// database reads. Changes made through this Authorization apply at once;
	// changes made elsewhere (another instance, SQL) apply within CacheTTL.
	// Default 30s; negative disables the cache.
	CacheTTL time.Duration
	// SeedWhitelist / SeedBlacklist are optional CIDRs or IPs inserted on
	// MigrateIPAccess when missing (idempotent by list+CIDR).
	SeedWhitelist []string
	SeedBlacklist []string
}

// IPEntry is one whitelist or blacklist rule. CIDR may be a single address
// ("203.0.113.10") or a network ("203.0.113.0/24", "2001:db8::/32").
type IPEntry struct {
	ID        string    `json:"id" gorm:"primaryKey;size:36"`
	List      string    `json:"list" gorm:"size:16;not null;uniqueIndex:idx_goauth_ip_list_cidr,priority:1"`
	CIDR      string    `json:"cidr" gorm:"column:cidr;size:64;not null;uniqueIndex:idx_goauth_ip_list_cidr,priority:2"`
	Label     string    `json:"label" gorm:"size:255"`
	Enabled   bool      `json:"enabled" gorm:"not null;default:true"`
	CreatedAt time.Time `json:"created_at" gorm:"not null"`
	UpdatedAt time.Time `json:"updated_at" gorm:"not null"`
}

// TableName is the default GORM table for IPEntry rows
// (DefaultTablePrefix + "ip_access_rules"). MigrateIPAccess and runtime
// queries still honor Config.TablePrefix / IPAccess.TableName.
func (IPEntry) TableName() string {
	return DefaultTablePrefix + ipAccessTableSuffix
}

// IPEntryUpdate is the mutable fields for UpdateWhitelistIP / UpdateBlacklistIP.
type IPEntryUpdate struct {
	CIDR    *string
	Label   *string
	Enabled *bool
}

type ipAccess struct {
	enabled       bool
	table         string
	seedWhitelist []string
	seedBlacklist []string
	cacheTTL      time.Duration

	mu       sync.Mutex
	rules    ipRuleSet
	loadedAt time.Time // zero when the cache must be reloaded
}

// ipRuleSet is the enabled rules, parsed once per load.
type ipRuleSet struct {
	whitelist, blacklist []*net.IPNet
}

func newIPAccess(o IPAccessOptions, tablePrefix string) (*ipAccess, error) {
	if !o.Enabled {
		return &ipAccess{}, nil
	}
	table := cmp.Or(o.TableName, tablePrefix+ipAccessTableSuffix)
	ttl := o.CacheTTL
	if ttl == 0 {
		ttl = defaultIPAccessCache
	}
	for _, list := range [][]string{o.SeedWhitelist, o.SeedBlacklist} {
		for _, raw := range list {
			if _, err := parseIPNet(raw); err != nil {
				return nil, fmt.Errorf("IPAccess seed entry %q: %w", raw, err)
			}
		}
	}
	return &ipAccess{
		enabled:       true,
		table:         table,
		seedWhitelist: slices.Clone(o.SeedWhitelist),
		seedBlacklist: slices.Clone(o.SeedBlacklist),
		cacheTTL:      ttl,
	}, nil
}

// MigrateIPAccess creates the IP access rules table and applies optional seeds.
func (a *Authorization) MigrateIPAccess(ctx context.Context) error {
	if a == nil || a.db == nil {
		return ErrNotInitialized
	}
	if a.ipAccess == nil || !a.ipAccess.enabled {
		return nil
	}
	if err := a.db.WithContext(ctx).Table(a.ipAccess.table).AutoMigrate(&IPEntry{}); err != nil {
		return err
	}
	for _, cidr := range a.ipAccess.seedWhitelist {
		if err := a.ensureIPEntry(ctx, ipListWhitelist, cidr, "seed"); err != nil {
			return err
		}
	}
	for _, cidr := range a.ipAccess.seedBlacklist {
		if err := a.ensureIPEntry(ctx, ipListBlacklist, cidr, "seed"); err != nil {
			return err
		}
	}
	return nil
}

func (a *Authorization) ensureIPEntry(ctx context.Context, list, cidr, label string) error {
	norm, err := normalizeCIDR(cidr)
	if err != nil {
		return err
	}
	var n int64
	if err := a.ipRules(ctx).Where("list = ? AND cidr = ?", list, norm).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err = a.addIPEntry(ctx, list, norm, label)
	return err
}

func (a *Authorization) ipRules(ctx context.Context) *gorm.DB {
	return a.db.WithContext(ctx).Table(a.ipAccess.table)
}

// --- Whitelist CRUD -----------------------------------------------------------

// AddWhitelistIP inserts an enabled whitelist entry.
func (a *Authorization) AddWhitelistIP(ctx context.Context, cidr, label string) (*IPEntry, error) {
	if err := a.requireIPAccess(); err != nil {
		return nil, err
	}
	return a.addIPEntry(ctx, ipListWhitelist, cidr, label)
}

// UpdateWhitelistIP updates CIDR, label and/or enabled on a whitelist row.
func (a *Authorization) UpdateWhitelistIP(ctx context.Context, id string, patch IPEntryUpdate) (*IPEntry, error) {
	if err := a.requireIPAccess(); err != nil {
		return nil, err
	}
	return a.updateIPEntry(ctx, ipListWhitelist, id, patch)
}

// RemoveWhitelistIP deletes a whitelist row by id.
func (a *Authorization) RemoveWhitelistIP(ctx context.Context, id string) error {
	if err := a.requireIPAccess(); err != nil {
		return err
	}
	return a.removeIPEntry(ctx, ipListWhitelist, id)
}

// ListWhitelistIPs returns all whitelist rows (enabled and disabled).
func (a *Authorization) ListWhitelistIPs(ctx context.Context) ([]IPEntry, error) {
	if err := a.requireIPAccess(); err != nil {
		return nil, err
	}
	return a.listIPEntries(ctx, ipListWhitelist)
}

// --- Blacklist CRUD -----------------------------------------------------------

// AddBlacklistIP inserts an enabled blacklist entry.
func (a *Authorization) AddBlacklistIP(ctx context.Context, cidr, label string) (*IPEntry, error) {
	if err := a.requireIPAccess(); err != nil {
		return nil, err
	}
	return a.addIPEntry(ctx, ipListBlacklist, cidr, label)
}

// UpdateBlacklistIP updates CIDR, label and/or enabled on a blacklist row.
func (a *Authorization) UpdateBlacklistIP(ctx context.Context, id string, patch IPEntryUpdate) (*IPEntry, error) {
	if err := a.requireIPAccess(); err != nil {
		return nil, err
	}
	return a.updateIPEntry(ctx, ipListBlacklist, id, patch)
}

// RemoveBlacklistIP deletes a blacklist row by id.
func (a *Authorization) RemoveBlacklistIP(ctx context.Context, id string) error {
	if err := a.requireIPAccess(); err != nil {
		return err
	}
	return a.removeIPEntry(ctx, ipListBlacklist, id)
}

// ListBlacklistIPs returns all blacklist rows (enabled and disabled).
func (a *Authorization) ListBlacklistIPs(ctx context.Context) ([]IPEntry, error) {
	if err := a.requireIPAccess(); err != nil {
		return nil, err
	}
	return a.listIPEntries(ctx, ipListBlacklist)
}

func (a *Authorization) requireIPAccess() error {
	if a == nil || a.db == nil {
		return ErrNotInitialized
	}
	if a.ipAccess == nil || !a.ipAccess.enabled {
		return errors.New("IP access control is not enabled")
	}
	return nil
}

func (a *Authorization) addIPEntry(ctx context.Context, list, cidr, label string) (*IPEntry, error) {
	norm, err := normalizeCIDR(cidr)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	row := &IPEntry{
		ID:        uuid.NewV4().String(),
		List:      list,
		CIDR:      norm,
		Label:     strings.TrimSpace(label),
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := a.ipRules(ctx).Create(row).Error; err != nil {
		return nil, err
	}
	a.ipAccess.invalidate()
	return row, nil
}

func (a *Authorization) updateIPEntry(ctx context.Context, list, id string, patch IPEntryUpdate) (*IPEntry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("id is required")
	}
	var row IPEntry
	if err := a.ipRules(ctx).Where("id = ? AND list = ?", id, list).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("ip entry %q not found", id)
		}
		return nil, err
	}
	if patch.CIDR != nil {
		norm, err := normalizeCIDR(*patch.CIDR)
		if err != nil {
			return nil, err
		}
		row.CIDR = norm
	}
	if patch.Label != nil {
		row.Label = strings.TrimSpace(*patch.Label)
	}
	if patch.Enabled != nil {
		row.Enabled = *patch.Enabled
	}
	row.UpdatedAt = time.Now().UTC()
	if err := a.ipRules(ctx).Save(&row).Error; err != nil {
		return nil, err
	}
	a.ipAccess.invalidate()
	return &row, nil
}

func (a *Authorization) removeIPEntry(ctx context.Context, list, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("id is required")
	}
	res := a.ipRules(ctx).Where("id = ? AND list = ?", id, list).Delete(&IPEntry{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("ip entry %q not found", id)
	}
	a.ipAccess.invalidate()
	return nil
}

func (a *Authorization) listIPEntries(ctx context.Context, list string) ([]IPEntry, error) {
	var rows []IPEntry
	err := a.ipRules(ctx).Where("list = ?", list).Order("created_at asc").Find(&rows).Error
	return rows, err
}

// --- Enforcement --------------------------------------------------------------

// allowClientIP reports whether the request's client IP may use goauth.
// Blacklist wins; if any enabled whitelist entries exist, the IP must match
// one of them.
func (a *Authorization) allowClientIP(ctx context.Context, ip string) (bool, error) {
	if a.ipAccess == nil || !a.ipAccess.enabled {
		return true, nil
	}
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false, nil
	}
	rules, err := a.loadIPRules(ctx)
	if err != nil {
		return false, err
	}
	if anyContains(rules.blacklist, parsed) {
		return false, nil
	}
	return len(rules.whitelist) == 0 || anyContains(rules.whitelist, parsed), nil
}

// loadIPRules returns the enabled rules, reading them with one query when the
// cache is empty or older than CacheTTL.
func (a *Authorization) loadIPRules(ctx context.Context) (ipRuleSet, error) {
	c := a.ipAccess
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cacheTTL > 0 && !c.loadedAt.IsZero() && time.Since(c.loadedAt) < c.cacheTTL {
		return c.rules, nil
	}
	var rows []IPEntry
	if err := a.ipRules(ctx).Select("list", "cidr").Where("enabled = ?", true).Find(&rows).Error; err != nil {
		return ipRuleSet{}, err
	}
	var rules ipRuleSet
	for _, row := range rows {
		n, err := parseIPNet(row.CIDR)
		if err != nil {
			continue
		}
		switch row.List {
		case ipListWhitelist:
			rules.whitelist = append(rules.whitelist, n)
		case ipListBlacklist:
			rules.blacklist = append(rules.blacklist, n)
		}
	}
	c.rules, c.loadedAt = rules, time.Now()
	return rules, nil
}

// invalidate makes the next check reload the rules.
func (c *ipAccess) invalidate() {
	c.mu.Lock()
	c.loadedAt = time.Time{}
	c.mu.Unlock()
}

func anyContains(nets []*net.IPNet, ip net.IP) bool {
	return slices.ContainsFunc(nets, func(n *net.IPNet) bool { return n.Contains(ip) })
}

// checkIPAccess writes a 403 response when the client IP is denied.
// It returns true when the response has already been written.
func (a *Authorization) checkIPAccess(w http.ResponseWriter, r *http.Request) bool {
	if a.ipAccess == nil || !a.ipAccess.enabled {
		return false
	}
	ok, err := a.allowClientIP(r.Context(), a.trustedClientIP(r))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Map{
			"code":    codeServerError,
			"message": msgSomethingWrong,
		})
		return true
	}
	if ok {
		return false
	}
	writeJSON(w, http.StatusForbidden, Map{
		"code":    codeIPForbidden,
		"message": msgIPForbidden,
	})
	return true
}

// wrapIPAccess runs the IP allow/deny check before every goauth route.
func (a *Authorization) wrapIPAccess(next http.Handler) http.Handler {
	if a.ipAccess == nil || !a.ipAccess.enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.checkIPAccess(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func normalizeCIDR(raw string) (string, error) {
	n, err := parseIPNet(raw)
	if err != nil {
		return "", err
	}
	return n.String(), nil
}

func parseIPNet(raw string) (*net.IPNet, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty address")
	}
	if strings.Contains(raw, "/") {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, err
		}
		return n, nil
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP %q", raw)
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}
