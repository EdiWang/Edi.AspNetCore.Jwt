using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace TestApi.Controllers;

[ApiController]
[Authorize]
[Route("api/[controller]")]
public class GoldController : ControllerBase
{
    public IActionResult Get()
    {
        return Ok("Gold");
    }
}