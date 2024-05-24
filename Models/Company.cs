namespace Aligned.Models
{
    public class Company
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string Address { get; set; }
        public string Telephone { get; set; }
        public string Mobile { get; set; }
        public string OwnerName { get; set; }
        public Guid CompanyTypeId { get; set; }
        public string CompanyTypeName { get; set; }
        public string ContactPersonName { get; set; }
        public string ContactPersonEmail { get; set; }
        public bool Active { get; set; }
 
    }
    public class CompanyCreateDto
    {
        public string Name { get; set; }
        public string Address { get; set; }
        public string Telephone { get; set; }
        public string Mobile { get; set; }
        public string OwnerName { get; set; }
        public Guid CompanyTypeId { get; set; }
        public string ContactPersonName { get; set; }
        public string ContactPersonEmail { get; set; }
        public bool Active { get; set; }
    }
    public class CompanyUpdateDto
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string Address { get; set; }
        public string Telephone { get; set; }
        public string Mobile { get; set; }
        public string OwnerName { get; set; }
        public Guid CompanyTypeId { get; set; }
        public string ContactPersonName { get; set; }
        public string ContactPersonEmail { get; set; }
        public bool Active { get; set; }
    }
}
