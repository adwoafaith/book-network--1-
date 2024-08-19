package com.faith.book.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private  final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    //(JWTAuthFilter)
    protected void doFilterInternal(
            @NotNull HttpServletRequest request,
            @NotNull HttpServletResponse response,
            @NotNull FilterChain filterChain
    ) throws ServletException, IOException {

        //here we extrat the authorization from the header from the request using the getHeader method into a variable called authHeader

        //(Check JWT Filter)
        final String authHeader = request.getHeader("Authorization");
        final String jwt;  //
        final String userEmail;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            //we don't want to continue the execution so we pass the request, response to the filterchain method to perform the next filter
            filterChain.doFilter(request, response);
            return;
        }

        //lets extract the token from the authorization header (from authHeader)
        jwt = authHeader.substring(7); //position 7 becos we count bearer which is 6 so we start counting from position 7

        //after extracting the token we also extract the userEmail
        //userEmail = //todo extract the user Email from JWT token we need a class for that;
        userEmail = jwtService.extractUsername(jwt);

        //we are checking if the user has not been authenticated yet
        if(userEmail!= null && SecurityContextHolder.getContext().getAuthentication() == null) {

            //if the securityContextholder is null it means the user has not been
            //authenticated so we have to go and fetch the user from the
            //database and see if the user is in the database

            //we have to get the userdetails from the database
            UserDetails  userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            if (jwtService.isTokenvalid(jwt, userDetails)) {

                //if user is valid we update the security context holder
                //we need to create an object called UsernamePasswordAuthenticationToken
                //now this object is needed so we can update the security holder
                //it takes the username as a parameter, the credentials, then the authorites
                //we don't have credentials yet that is why we are passing null

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                //lets set the details
                //so we will build the details based on the request of the user
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                //now let's update the security contextholder
                SecurityContextHolder.getContext().setAuthentication(authToken);


            }
        }
        filterChain.doFilter(request, response);
    }
}
