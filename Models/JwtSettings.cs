namespace Aligned.Models
{
    public class JwtSettings
    {
        public string JwtIssuer { get; set; }
        public string JwtAudience { get; set; }
        public string JwtSigningSecret { get; set; }
        public int ExpiryToken { get; set; }
    }
}
