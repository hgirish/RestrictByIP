using System.Web;
using System.Web.Mvc;
using RestrictByIP.Filters;

namespace RestrictByIP
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());

            filters.Add(new FilterIPAttribute(
             "AllowedSingleIPs",
             "AllowedMaskedIPs",
             "DeniedSingleIPs",
             "DeniedMaskedIPs"
       ));
        }
    }
}
