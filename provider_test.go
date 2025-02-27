package goauth_test

// func Test_UseProviders(t *testing.T) {
// 	a := assert.New(t)

// 	provider := &faux.Provider{}
// 	goauth.UseProviders(provider)
// 	a.Equal(len(goauth.GetProviders()), 1)
// 	a.Equal(goauth.GetProviders()[provider.Name()], provider)
// 	goauth.ClearProviders()
// }

// func Test_GetProvider(t *testing.T) {
// 	a := assert.New(t)

// 	provider := &faux.Provider{}
// 	goauth.UseProviders(provider)

// 	p, err := goauth.GetProvider(provider.Name())
// 	a.NoError(err)
// 	a.Equal(p, provider)

// 	_, err = goauth.GetProvider("unknown")
// 	a.Error(err)
// 	a.Equal(err.Error(), "no provider for unknown exists")
// 	goauth.ClearProviders()
// }
