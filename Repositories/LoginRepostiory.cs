using Aligned.IRepositories;
using Aligned.Models;
using System.Data.Common;
using System.Data.SqlClient;

namespace Aligned.Repositories
{
    public class LoginRepostiory: ILoginRepository
    {
        private readonly SqlConnection _connection;

        public LoginRepostiory(IConfiguration configuration)
        {
            _connection = new SqlConnection(configuration.GetConnectionString("DefaultConnection"));
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
                throw new Exception("An error occurred while AuthenticateUser.", ex);
            }
            finally
            {
                if (_connection.State == System.Data.ConnectionState.Open)
                {
                    _connection.Close();
                }
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
                throw new Exception("An error occurred while GetUserByEmail.", ex);
            }
            finally
            {
                if (_connection.State == System.Data.ConnectionState.Open)
                {
                    _connection.Close();
                }
            }
            return user;
        }

        public User GetUserById(Guid userId)
        {
            User user = null;
            try
            {
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
            }
            catch (Exception ex)
            {
                throw new Exception("An error occurred while GetUserById.", ex);
            }
            finally
            {
                if (_connection.State == System.Data.ConnectionState.Open)
                {
                    _connection.Close();
                }
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
                throw new Exception("An error occurred while GetUserRoles.", ex);
            }
            finally
            {
                if (_connection.State == System.Data.ConnectionState.Open)
                {
                    _connection.Close();
                }
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
                throw new Exception("An error occurred while GetUserPermissions.", ex);
            }
            finally
            {
                if (_connection.State == System.Data.ConnectionState.Open)
                {
                    _connection.Close();
                }
            }
            return permissions;
        }
    }
}
