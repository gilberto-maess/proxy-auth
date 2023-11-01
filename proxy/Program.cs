using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Logging;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

builder.Services
    .AddAuthentication(cfg =>
    {
        cfg.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        cfg.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.CookieManager = new ChunkingCookieManager();
    })
    .AddOpenIdConnect(cfg =>
    {
        cfg.Authority = builder.Configuration["SSO_AUTHORITY"];
        cfg.ClientId = builder.Configuration["SSO_CLIENT_ID"];
        cfg.ClientSecret = builder.Configuration["SSO_CLIENT_SECRET"];
        cfg.UsePkce = true;
        cfg.RequireHttpsMetadata = false;

        cfg.Scope.Clear();
        cfg.Scope.Add("openid");
        cfg.Scope.Add("profile");
    });
    
builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.CheckConsentNeeded = context => false;
    options.MinimumSameSitePolicy = SameSiteMode.None;
});
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.SecurePolicy = CookieSecurePolicy.None;
    options.Cookie.SameSite = SameSiteMode.Lax;
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("customPolicy", policy =>
        policy.RequireAuthenticatedUser());
});

var app = builder.Build();
IdentityModelEventSource.ShowPII = true;
var options = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.All
};
options.KnownNetworks.Clear();
options.KnownProxies.Clear();
app.UseForwardedHeaders(options);
app.UseRouting();
app.UseCookiePolicy();
app.UseAuthentication();
app.UseAuthorization();
app.UseEndpoints(endpoints =>
{
    endpoints.MapReverseProxy();
});
app.Run();
