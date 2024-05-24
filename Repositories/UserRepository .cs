using Aligned.Models;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Aligned.IRepositories;

namespace Aligned.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly SqlConnection _connection;

        public UserRepository(IConfiguration configuration)
        {
            _connection = new SqlConnection(configuration.GetConnectionString("DefaultConnection"));
        }

        public void CreateUser(User user)
        {
            if (!Helper.IsPasswordComplex(user.Password))
            {
                throw new ArgumentException("Password does not meet complexity requirements.");
            }

            byte[] encryptedPassword = Helper.EncryptStringToBytes_Aes(user.Password);

            try
            {
                using (SqlCommand command = new SqlCommand("SP_CreateUser", _connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.AddWithValue("@Id", Guid.NewGuid());
                    command.Parameters.AddWithValue("@Email", user.Email);
                    command.Parameters.AddWithValue("@FullName", user.FullName);
                    command.Parameters.AddWithValue("@Password", encryptedPassword);
                    command.Parameters.AddWithValue("@Active", user.Active);

                    _connection.Open();
                    command.ExecuteNonQuery();
                    _connection.Close();
                }
            }
            catch (SqlException ex)
            {
                if (ex.Number == 50000 && ex.Message.Contains("Email already exists"))
                {
                    throw new Exception("Email already exists. Please use a different email.");
                }
                throw;
            }
        }
        public void UpdateUser(User user)
        {
            if (!Helper.IsPasswordComplex(user.Password))
            {
                throw new ArgumentException("Password does not meet complexity requirements.");
            }

            byte[] encryptedPassword = Helper.EncryptStringToBytes_Aes(user.Password);

            try
            {
                using (SqlCommand command = new SqlCommand("SP_UpdateUser", _connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.AddWithValue("@Id", user.Id);
                    command.Parameters.AddWithValue("@Email", user.Email);
                    command.Parameters.AddWithValue("@FullName", user.FullName);
                    command.Parameters.AddWithValue("@Password", encryptedPassword);
                    command.Parameters.AddWithValue("@Active", user.Active);

                    _connection.Open();
                    command.ExecuteNonQuery();
                    _connection.Close();
                }
            }
            catch (SqlException ex)
            {
                if (ex.Message.Contains("The email address is already in use by another user."))
                {
                    throw new Exception("Email already exists. Please use a different email.");
                }
                throw;
            }
        }

        public bool AuthenticateUser(string email, string password)
        {
            try
            {
                using (SqlCommand command = new SqlCommand("SP_AuthenticateUser", _connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;
                    command.Parameters.AddWithValue("@Email", email);

                    _connection.Open();
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            byte[] storedPassword = (byte[])reader["Password"];
                            string decryptedPassword = Helper.DecryptStringFromBytes_Aes(storedPassword);

                            _connection.Close();
                            return decryptedPassword == password;
                        }
                    }
                    _connection.Close();
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Authentication failed.", ex);
            }
            return false;
        }

        public User GetUserByEmail(string email)
        {
            User user = null;
            try
            {
                using (SqlCommand command = new SqlCommand("SP_GetUserByEmail", _connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;
                    command.Parameters.AddWithValue("@Email", email);

                    _connection.Open();
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            user = new User
                            {
                                Id = (Guid)reader["Id"],
                                Email = reader["Email"].ToString(),
                                FullName = reader["FullName"].ToString(),
                                Password = Helper.DecryptStringFromBytes_Aes((byte[])reader["Password"]),
                                Active = (bool)reader["Active"]
                            };
                        }
                    }
                    _connection.Close();
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Error getting user by email.", ex);
            }

            return user;
        }

        public List<string> GetUserRoles(Guid userId)
        {
            List<string> roles = new List<string>();

            try
            {
                using (SqlCommand command = new SqlCommand("SP_GetUserRoles", _connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;
                    command.Parameters.AddWithValue("@UserId", userId);

                    _connection.Open();
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            roles.Add(reader["RoleName"].ToString());
                        }
                    }
                    _connection.Close();
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Error getting user roles.", ex);
            }

            return roles;
        }

        public List<Permission> GetUserPermissions(Guid userId)
        {
            List<Permission> permissions = new List<Permission>();

            try
            {
                using (SqlCommand command = new SqlCommand("SP_GetUserPermissions", _connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;
                    command.Parameters.AddWithValue("@UserId", userId);

                    _connection.Open();
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            permissions.Add(new Permission
                            {
                                PageName = reader["PageName"].ToString(),
                                CanAdd = (bool)reader["CanAdd"],
                                CanEdit = (bool)reader["CanEdit"],
                                CanDelete = (bool)reader["CanDelete"],
                                CanView = (bool)reader["CanView"],
                                CanList = (bool)reader["CanList"],
                                CanImport = (bool)reader["CanImport"],
                                CanExport = (bool)reader["CanExport"]
                            });
                        }
                    }
                    _connection.Close();
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Error getting user permissions.", ex);
            }

            return permissions;
        }
    }
}
