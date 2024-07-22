namespace Keycloak_API
{
    public class UserModel
    {
        public int user_id { get; set; }
        public string user_name { get; set; }
        public string user_email { get; set; }
        public string user_password { get; set; }
        public List<string> Roles { get; set; } // List of roles assigned to the user

    }
}
