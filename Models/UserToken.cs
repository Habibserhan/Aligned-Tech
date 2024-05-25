using System;

namespace Aligned.Models
{
    public class UserToken
    {
        public Guid TokenId { get; set; }
        public Guid UserId { get; set; }
        public string Token { get; set; }
        public string Email { get; set; }
        public DateTime CreatedAt { get; set; }
        public string IpAddress { get; set; }
        public string Browser { get; set; }
        public string PcName { get; set; }
        public DateTime Expiry { get; set; }
        public string Refreshtoken { get; set; }

    }
}
