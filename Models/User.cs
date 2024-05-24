namespace Aligned.Models
{
    public class User
    {
        public Guid Id { get; set; } // Primary key
        public string Email { get; set; }
        public string FullName { get; set; }
        public string Password { get; set; }
        public bool Active { get; set; }
    }

}
