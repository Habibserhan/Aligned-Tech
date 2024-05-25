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
            byte[] encryptedPassword = Helper.EncryptStringToBytes_Aes(user.Password);

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

        public bool AuthenticateUser(string email, string password)
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
            return false;
        }

        public User GetUserByEmail(string email)
        {
            User user = null;

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

            return user;
        }

        public User GetUserById(Guid userId)
        {
            User user = null;

            using (SqlCommand command = new SqlCommand("SP_GetUserById", _connection))
            {
                command.CommandType = System.Data.CommandType.StoredProcedure;
                command.Parameters.AddWithValue("@Id", userId);

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

            return user;
        }

        public void UpdateUser(User user)
        {
            byte[] encryptedPassword = Helper.EncryptStringToBytes_Aes(user.Password);

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

        public List<string> GetUserRoles(Guid userId)
        {
            List<string> roles = new List<string>();

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

            return roles;
        }

        public List<Permission> GetUserPermissions(Guid userId)
        {
            List<Permission> permissions = new List<Permission>();

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

            return permissions;
        }
    }
}
