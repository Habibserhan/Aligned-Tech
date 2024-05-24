using Aligned.IRepositories;
using Aligned.Models;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;

namespace Aligned.Repositories
{
    public class CompanyRepository : ICompanyRepository
    {
        private readonly SqlConnection _connection;

        public CompanyRepository(IConfiguration configuration)
        {
            _connection = new SqlConnection(configuration.GetConnectionString("DefaultConnection"));
        }

        public void CreateCompany(Company company)
        {
            try
            {
                using (SqlCommand command = new SqlCommand("SP_CreateCompany", _connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.AddWithValue("@Id", Guid.NewGuid());
                    command.Parameters.AddWithValue("@Name", company.Name);
                    command.Parameters.AddWithValue("@Address", company.Address);
                    command.Parameters.AddWithValue("@Telephone", company.Telephone);
                    command.Parameters.AddWithValue("@Mobile", company.Mobile);
                    command.Parameters.AddWithValue("@OwnerName", company.OwnerName);
                    command.Parameters.AddWithValue("@CompanyTypeId", company.CompanyTypeId);
                    command.Parameters.AddWithValue("@ContactPersonName", company.ContactPersonName);
                    command.Parameters.AddWithValue("@ContactPersonEmail", company.ContactPersonEmail);
                    command.Parameters.AddWithValue("@Active", company.Active);

                    _connection.Open();
                    command.ExecuteNonQuery();
                    _connection.Close();
                }
            }
            catch (Exception ex)
            {
                throw new Exception("An error occurred while creating the company.", ex);
            }
        }

        public void UpdateCompany(Company company)
        {
            try
            {
                using (SqlCommand command = new SqlCommand("SP_UpdateCompany", _connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.AddWithValue("@Id", company.Id);
                    command.Parameters.AddWithValue("@Name", company.Name);
                    command.Parameters.AddWithValue("@Address", company.Address);
                    command.Parameters.AddWithValue("@Telephone", company.Telephone);
                    command.Parameters.AddWithValue("@Mobile", company.Mobile);
                    command.Parameters.AddWithValue("@OwnerName", company.OwnerName);
                    command.Parameters.AddWithValue("@CompanyTypeId", company.CompanyTypeId);
                    command.Parameters.AddWithValue("@ContactPersonName", company.ContactPersonName);
                    command.Parameters.AddWithValue("@ContactPersonEmail", company.ContactPersonEmail);
                    command.Parameters.AddWithValue("@Active", company.Active);

                    _connection.Open();
                    command.ExecuteNonQuery();
                    _connection.Close();
                }
            }
            catch (Exception ex)
            {
                throw new Exception("An error occurred while updating the company.", ex);
            }
        }

        public void DeleteCompany(Guid companyId)
        {
            try
            {
                using (SqlCommand command = new SqlCommand("SP_DeleteCompany", _connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;
                    command.Parameters.AddWithValue("@Id", companyId);

                    _connection.Open();
                    command.ExecuteNonQuery();
                    _connection.Close();
                }
            }
            catch (Exception ex)
            {
                throw new Exception("An error occurred while deleting the company.", ex);
            }
        }

        public Company GetCompanyById(Guid companyId)
        {
            Company company = null;

            try
            {
                using (SqlCommand command = new SqlCommand("SP_GetCompanyById", _connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;
                    command.Parameters.AddWithValue("@Id", companyId);

                    _connection.Open();
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            company = new Company
                            {
                                Id = (Guid)reader["Id"],
                                Name = reader["Name"].ToString(),
                                Address = reader["Address"].ToString(),
                                Telephone = reader["Telephone"].ToString(),
                                Mobile = reader["Mobile"].ToString(),
                                OwnerName = reader["OwnerName"].ToString(),
                                CompanyTypeId = (Guid)reader["CompanyTypeId"],
                                ContactPersonName = reader["ContactPersonName"].ToString(),
                                ContactPersonEmail = reader["ContactPersonEmail"].ToString(),
                                Active = (bool)reader["Active"]
                            };
                        }
                    }
                    _connection.Close();
                }
            }
            catch (Exception ex)
            {
                throw new Exception("An error occurred while retrieving the company.", ex);
            }

            return company;
        }

        public List<Company> GetAllCompanies()
        {
            List<Company> companies = new List<Company>();

            try
            {
                using (SqlCommand command = new SqlCommand("SP_GetAllCompanies", _connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    _connection.Open();
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            companies.Add(new Company
                            {
                                Id = (Guid)reader["Id"],
                                Name = reader["Name"].ToString(),
                                Address = reader["Address"].ToString(),
                                Telephone = reader["Telephone"].ToString(),
                                Mobile = reader["Mobile"].ToString(),
                                OwnerName = reader["OwnerName"].ToString(),
                                CompanyTypeId = (Guid)reader["CompanyTypeId"],
                                CompanyTypeName = reader["CompanyTypeName"].ToString(),
                                ContactPersonName = reader["ContactPersonName"].ToString(),
                                ContactPersonEmail = reader["ContactPersonEmail"].ToString(),
                                Active = (bool)reader["Active"]
                            });
                        }
                    }
                    _connection.Close();
                }
            }
            catch (Exception ex)
            {
                throw new Exception("An error occurred while retrieving the companies.", ex);
            }

            return companies;
        }
    }
}
