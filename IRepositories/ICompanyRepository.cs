using Aligned.Models;
using System;
using System.Collections.Generic;

namespace Aligned.IRepositories
{
    public interface ICompanyRepository
    {
        void CreateCompany(Company company);
        void UpdateCompany(Company company);
        void DeleteCompany(Guid companyId);
        Company GetCompanyById(Guid companyId);
        List<Company> GetAllCompanies();
    }
}
