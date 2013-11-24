using System.Web.Mvc;

namespace RestrictByIP.Controllers
{
    public class ErrorController : Controller
    {
        public ActionResult Forbidden()
        {
            return View();
        }
	}
}