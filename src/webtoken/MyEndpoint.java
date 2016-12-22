package webtoken;

import java.net.URI;

import javax.ws.rs.CookieParam;

import javax.ws.rs.GET;

import org.apache.commons.codec.binary.Base64;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

import javax.ws.rs.core.UriBuilder;

import org.json.JSONObject;

@Path("/")
public class MyEndpoint 
{
    @GET
    @Path("status")
    public Response getRequest() throws Exception
    {
        UriBuilder ub = UriBuilder.fromPath("../").path("Login.html");
        URI        uri = ub.build("Invalid Login", "Login Again");
        return Response.temporaryRedirect(uri).build();
    }
    
    @POST
    @Secured
    @Path("status")
    @Produces("application/json")
    @SuppressWarnings("org.adfemg.audits.java.system-out-usage")
    public Response isLoggedIn(@CookieParam("token") String token) throws Exception
    {
        // This method is annotated with @Secured
        // The authentication filter will be executed before invoking this method
        // The HTTP request must be performed with a valid token

        String encodedToken = token;
        
        Token  t = new Token(new String(Base64.decodeBase64(encodedToken.getBytes())));
        
        JSONObject j = t.validateToken();

        String output = "Token Data: " +
                        "\n    Username:         " + j.getString("login") + 
                        "\n    Token Issued:     " + j.getString("TokenIssued") + 
                        "\n    Token Expiration: " + j.getString("TokenExpiration") + 
                        "\n    Current Time:     " + j.getString("CurrentTime") + 
                        "\n    Token Expired:    " + j.getString("TokenExpired");
        
        System.out.println(output);
        
        if (j.getString("TokenExpired").equalsIgnoreCase("false"))
            return Response.ok(output).build();
        else
        {
            //Redirect to Login Page - Token Expired
            UriBuilder ub = UriBuilder.fromPath("../").path("Login.html");
            URI uri = ub.build("TokenExpired", "Login Again");
            return Response.temporaryRedirect(uri).build();
        }           
    }
}