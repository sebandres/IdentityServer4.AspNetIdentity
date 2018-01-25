using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer4.Quickstart.UI
{
    /// <summary>
    /// This sample controller allows a user to revoke grants given to clients
    /// </summary>
    [SecurityHeaders]
    [Authorize]
    public class ClaimsController : Controller
    {
        /// <summary>
        /// Show list of claims
        /// </summary>
        [HttpGet]
        public IActionResult Index()
        {
            return View();
        }
    }
}