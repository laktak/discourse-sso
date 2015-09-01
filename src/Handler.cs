using System;
using System.Linq;
using System.Collections.Specialized;
using System.Configuration;
using System.Security.Principal;
using System.Text;
using System.Web;
using System.DirectoryServices.AccountManagement;
using System.IO;

namespace DiscSso
{
  public class Handler : IHttpHandler
  {
    // config
    static string[] allow=ConfigurationManager.AppSettings["Allow"].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).ToArray();
    static string secret=ConfigurationManager.AppSettings["Secret"];
    static string domainController=ConfigurationManager.AppSettings["DomainController"];
    static string discourseUrl=ConfigurationManager.AppSettings["DiscourseUrl"];
    static readonly string[] validAuthTypes= { "ntlm", "kerberos", "negotiate" };
    const string error="Error.html";

    public bool IsReusable
    {
      get { return true; }
    }

    public void ProcessRequest(HttpContext ctx)
    {
      string rpath=ctx.Request.AppRelativeCurrentExecutionFilePath;
      if (rpath=="~/login") login(ctx);
      else if (rpath=="~/test")
      {
        try { write(ctx, 200, "text/plain", "/?"+getAuth("null")); }
        catch (Exception e) { write(ctx, 500, "text/plain", e.ToString()); }
      }
      else if (rpath=="~/error") writeFile(ctx, 500, error, "Login failed ("+ctx.Request.QueryString["msg"]+")!");
      else writeFile(ctx, 404, error, "Page not found.");
    }

    void write(HttpContext ctx, int statusCode, string contentType, string text)
    {
      var resp=ctx.Response;
      resp.Clear();
      resp.ContentType=contentType;
      resp.TrySkipIisCustomErrors=true;
      resp.StatusCode=statusCode;
      resp.Write(text);
    }

    void writeFile(HttpContext ctx, int statusCode, string file, string text=null)
    {
      string body=File.ReadAllText(ctx.Server.MapPath("~/"+file));
      write(ctx, statusCode, "text/html", body.Replace("{0}", text));
    }

    void login(HttpContext ctx)
    {
      HttpRequest request=ctx.Request;
      try
      {
        if (string.IsNullOrEmpty(request.QueryString["sso"]) || string.IsNullOrEmpty(request.QueryString["sig"]))
          throw new Exception("args");

        string sso=request.QueryString["sso"];
        string sig=request.QueryString["sig"];

        string checksum=getSsoHash(sso);
        if (checksum!=sig) throw new Exception("invalid");

        string decodedSso=Encoding.UTF8.GetString(Convert.FromBase64String(sso));
        var ssoArgs=HttpUtility.ParseQueryString(decodedSso);
        string returnPayload=getAuth(ssoArgs["nonce"]);
        string encodedPayload=Convert.ToBase64String(Encoding.UTF8.GetBytes(returnPayload));
        string returnSig=getSsoHash(encodedPayload);
        string redirectUrl=discourseUrl+"/session/sso_login?sso="+encodedPayload+"&sig="+returnSig;

        ctx.Response.Redirect(redirectUrl, false);
      }
      catch (Exception e)
      {
        ctx.Response.Redirect("~/error?msg="+e.Message, false);
      }
    }

    string getAuth(string nonce)
    {
      WindowsIdentity wid=HttpContext.Current.Request.LogonUserIdentity;
      if (wid==null || !wid.IsAuthenticated || !validAuthTypes.Contains(wid.AuthenticationType.ToLower()))
        throw new Exception("Not authenticated (you need to disable anon and enable Windows authentication in IIS)!");
      var wp=new WindowsPrincipal(wid);
      if (!allow.Any(x => wp.IsInRole(x)))
        throw new Exception("access-denied");

      string externalId=wid.Name;
      string username=externalId, email=null, name=null;

      // try to get user info from Active Directory
      using (var pctx=new PrincipalContext(ContextType.Domain))
        getAccount(pctx, wid.Name, out email, out name);

      if (email==null && !string.IsNullOrEmpty(domainController))
      {
        // retry on specified DC
        using (var pctx=new PrincipalContext(ContextType.Domain, domainController))
          getAccount(pctx, wid.Name, out email, out name);
      }

      if (email==null) throw new Exception("Can't get user "+wid.Name+" from domain!");

      // strip domain from username
      int idx=username.IndexOf('\\');
      if (idx>=0) username=username.Substring(idx+1);

      Func<string, string> enc=HttpContext.Current.Server.UrlEncode;
      return "nonce="+enc(nonce)+
        "&email="+enc(email)+
        "&external_id="+enc(externalId)+
        "&username="+enc(username)+
        "&name="+enc(name);
    }

    void getAccount(PrincipalContext ctx, string domName, out string email, out string name)
    {
      name=email=null;
      using (var usr=UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, domName))
      {
        if (usr!=null)
        {
          name=usr.GivenName+" "+usr.Surname;
          email=usr.EmailAddress;
        }
      }
    }

    string getSsoHash(string payload)
    {
      var hash=new System.Security.Cryptography.HMACSHA256(Encoding.UTF8.GetBytes(secret)).ComputeHash(Encoding.UTF8.GetBytes(payload));
      return string.Join("", hash.Select(b => String.Format("{0:x2}", b)));
    }
  }
}
