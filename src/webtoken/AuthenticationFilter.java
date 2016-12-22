package webtoken;

import java.io.IOException;

import javax.annotation.Priority;

import javax.servlet.http.HttpServletRequest;

import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;

import org.apache.commons.codec.binary.Base64;

import org.json.JSONObject;

@Secured
@Provider
@Priority(Priorities.AUTHENTICATION)
public class AuthenticationFilter implements ContainerRequestFilter
{
    @Context
    HttpServletRequest request;
    
    @Override
    @SuppressWarnings("org.adfemg.audits.java.system-out-usage")
    public void filter(ContainerRequestContext requestContext) throws IOException
    {
        // Get the HTTP Authorization header from the request
        //String authorizationHeader = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);

        //MultivaluedMap<String, String> pathparam = requestContext.getUriInfo().getPathParameters();
        
        //String encodedToken = pathparam.get("token").toString();

        String encodedToken = request.getParameter("token");

        //encodedToken = encodedToken.substring(1, encodedToken.length() - 1);

        //System.out.println("ENCRYPTED TOKEN BEFORE DECODING -> " + encodedToken);
        String decodedToken = new String(Base64.decodeBase64(encodedToken.getBytes()));
        //System.out.println("ENCRYPTED TOKEN AFTER DECODING -> " + decodedToken);
        
        Token token = new Token(decodedToken);
        
        /*// Check if the HTTP Authorization header is present and formatted correctly
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer "))
        {
            throw new NotAuthorizedException("Authorization header must be provided");
        }

        // Extract the token from the HTTP Authorization header
        //String token = authorizationHeader.substring("Bearer".length()).trim();
        */
        
        try
        {
            // Validate the token
            JSONObject j = token.validateToken();
            System.out.println("Token Validated Successfully");
        }
        catch (Exception e)
        {
            requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }
}