using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Demo.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    public record AuthRequest(string Username, string Password);
    public record UserData(string UserId, string UserName);

    private readonly List<(string Id, string Username, string Password)> _users = new()
    {
        ("1", "admin", "1234"),
        ("2", "ali", "1234"),
        ("3", "mona", "5678")
    };

    private readonly IConfiguration _config;

    public AuthController(IConfiguration config)
    {
        _config = config;
    }

    // POST api/auth/token
    [HttpPost("token")]
    public ActionResult<string> Authenticate([FromBody] AuthRequest data)
    {
        var user = ValidateCredentials(data);
        if (user == null)
            return Unauthorized("Invalid username or password");

        var token = GenerateJwtToken(user);
        return Ok(token);
    }

    private UserData? ValidateCredentials(AuthRequest data)
    {
        var user = _users.FirstOrDefault(u =>
            string.Equals(u.Username, data.Username, StringComparison.OrdinalIgnoreCase)
            && u.Password == data.Password);

        return user == default ? null : new UserData(user.Id, user.Username);
    }

    private string GenerateJwtToken(UserData user)
    {
        
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.UserId),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString())
        };

        claims.Add(new Claim(ClaimTypes.Role, user.UserName == "admin" ? "Admin" : "User"));

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(30),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

}
