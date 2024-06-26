﻿using Aligned.IRepositories;
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
            var result = Helper.ValidateTokenAndPermission(_connection, token, "Company", "CanAdd", HttpContext);
            if (result != null)
            {
                return result;
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
                return Helper.CreatedResponse();
            }
            catch (Exception ex)
            {
                return Helper.FailureResponse(ex.Message);
            }
        }

        [HttpPost("update")]
        public async Task<IActionResult> Update([FromBody] CompanyUpdateDto companyDto)
        {
            string token = HttpContext.Request.Headers["Authorization"].ToString().Split(' ')[1];
            var result = Helper.ValidateTokenAndPermission(_connection, token, "Company", "CanEdit", HttpContext);
            if (result != null)
            {
                return result;
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
                return Helper.UpdateResponse();
            }
            catch (Exception ex)
            {
                return Helper.FailureResponse(ex.Message);
            }
        }

        [HttpPost("delete")]
        public async Task<IActionResult> Delete([FromBody] Guid id)
        {
            string token = HttpContext.Request.Headers["Authorization"].ToString().Split(' ')[1];
            var result = Helper.ValidateTokenAndPermission(_connection, token, "Company", "CanDelete", HttpContext);
            if (result != null)
            {
                return result;
            }

            try
            {
                _companyRepository.DeleteCompany(id);
                 return Helper.DeleteResponse();
            }
            catch (Exception ex)
            {
                return Helper.FailureResponse(ex.Message);
            }
        }

        [HttpGet("get/{id}")]
        public async Task<IActionResult> GetCompanyById(Guid id)
        {
            string token = HttpContext.Request.Headers["Authorization"].ToString().Split(' ')[1];
            var result = Helper.ValidateTokenAndPermission(_connection, token, "Company", "canList", HttpContext);
            if (result != null)
            {
                return result;
            }
            try
            {
                var Data = _companyRepository.GetCompanyById(id);
                return Helper.GetByIdResponse(Data);
            }
            catch (Exception ex)
            {
                return Helper.FailureResponse(ex.Message);
            }
        }

        [HttpGet("all")]
        public async Task<IActionResult> GetAllCompanies()
        {
            string token = HttpContext.Request.Headers["Authorization"].ToString().Split(' ')[1];
            var result = Helper.ValidateTokenAndPermission(_connection, token, "Company", "canList", HttpContext);
            if (result != null)
            {
                return result;
            }
            try
            {
                var Data = _companyRepository.GetAllCompanies();
                return Helper.GetAllResponse(Data);
            }
            catch (Exception ex)
            {
                return Helper.FailureResponse(ex.Message);
            }
        }
    }
}
