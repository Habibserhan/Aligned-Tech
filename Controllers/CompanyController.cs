using Aligned.IRepositories;
using Aligned.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Data.SqlClient;
using System.Threading.Tasks;

namespace Aligned.Controllers
{
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{v:apiVersion}/[controller]")]
    public class CompanyController : ControllerBase
    {
        private readonly ICompanyRepository _companyRepository;
        private readonly SqlConnection _connection;

        public CompanyController(ICompanyRepository companyRepository, IConfiguration configuration)
        {
            _companyRepository = companyRepository;
            _connection = new SqlConnection(configuration.GetConnectionString("DefaultConnection"));
        }

        [HttpPost("create")]
        public async Task<IActionResult> Create([FromBody] CompanyCreateDto companyDto)
        {
            string token = HttpContext.Request.Headers["Authorization"].ToString().Split(' ')[1];
            if (!Helper.CheckTokenValidity(_connection, token, HttpContext))
            {
                return Unauthorized();
            }

            var userId = Helper.GetUserIdFromToken(token);

            if (!Helper.HasPermission(_connection, userId, "Company", "CanAdd"))
            {
                return Forbid();
            }

            try
            {
                var company = new Company
                {
                    Id = Guid.NewGuid(),
                    Name = companyDto.Name,
                    Address = companyDto.Address,
                    Telephone = companyDto.Telephone,
                    Mobile = companyDto.Mobile,
                    OwnerName = companyDto.OwnerName,
                    CompanyTypeId = companyDto.CompanyTypeId,
                    ContactPersonName = companyDto.ContactPersonName,
                    ContactPersonEmail = companyDto.ContactPersonEmail,
                    Active = companyDto.Active
                };

                _companyRepository.CreateCompany(company);
                return new JsonResult(new { success = true, message = "Company created successfully" });
            }
            catch (Exception ex)
            {
                return new JsonResult(new { success = false, message = ex.Message });
            }
        }

        [HttpPost("update")]
        public async Task<IActionResult> Update([FromBody] CompanyUpdateDto companyDto)
        {
            string token = HttpContext.Request.Headers["Authorization"].ToString().Split(' ')[1];
            if (!Helper.CheckTokenValidity(_connection, token, HttpContext))
            {
                return Unauthorized();
            }

            var userId = Helper.GetUserIdFromToken(token);

            if (!Helper.HasPermission(_connection, userId, "Company", "CanEdit"))
            {
                return Forbid();
            }

            try
            {
                var company = new Company
                {
                    Id = companyDto.Id,
                    Name = companyDto.Name,
                    Address = companyDto.Address,
                    Telephone = companyDto.Telephone,
                    Mobile = companyDto.Mobile,
                    OwnerName = companyDto.OwnerName,
                    CompanyTypeId = companyDto.CompanyTypeId,
                    ContactPersonName = companyDto.ContactPersonName,
                    ContactPersonEmail = companyDto.ContactPersonEmail,
                    Active = companyDto.Active
                };

                _companyRepository.UpdateCompany(company);
                return new JsonResult(new { success = true, message = "Company updated successfully" });
            }
            catch (Exception ex)
            {
                return new JsonResult(new { success = false, message = ex.Message });
            }
        }

        [HttpPost("delete")]
        public async Task<IActionResult> Delete([FromBody] Guid id)
        {
            string token = HttpContext.Request.Headers["Authorization"].ToString().Split(' ')[1];
            if (!Helper.CheckTokenValidity(_connection, token, HttpContext))
            {
                return Unauthorized();
            }

            var userId = Helper.GetUserIdFromToken(token);

            if (!Helper.HasPermission(_connection, userId, "Company", "CanDelete"))
            {
                return Forbid();
            }

            try
            {
                _companyRepository.DeleteCompany(id);
                return new JsonResult(new { success = true, message = "Company deleted successfully" });
            }
            catch (Exception ex)
            {
                return new JsonResult(new { success = false, message = ex.Message });
            }
        }

        [HttpGet("get/{id}")]
        public async Task<IActionResult> GetCompanyById(Guid id)
        {
            try
            {
                var company = _companyRepository.GetCompanyById(id);
                return new JsonResult(new { success = true, data = company });
            }
            catch (Exception ex)
            {
                return new JsonResult(new { success = false, message = ex.Message });
            }
        }

        [HttpGet("all")]
        public async Task<IActionResult> GetAllCompanies()
        {
            try
            {
                var companies = _companyRepository.GetAllCompanies();
                return new JsonResult(new { success = true, data = companies });
            }
            catch (Exception ex)
            {
                return new JsonResult(new { success = false, message = ex.Message });
            }
        }
    }
}
