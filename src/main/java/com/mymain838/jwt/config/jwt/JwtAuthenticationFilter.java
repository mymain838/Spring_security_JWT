package com.mymain838.jwt.config.jwt;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mymain838.jwt.config.auth.PrincipalDetails;
import com.mymain838.jwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음.
//login 요청을해서 username, password 전송하면 (post)
//UsernamePassword
@RequiredArgsConstructor
public class JwtAuthenticationFilter  extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager; // 생성자로 받아옴
    //login 요청을 하면 로그인 시도를 위해서 실행되는 함수(attemptAuthentication)
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //1. username, password 받기(x-www-form encoded)
        try {

           /* BufferedReader br = request.getReader();
            String input = null;
            while((input = br.readLine())!=null){
                System.out.println(input);
            }   */
            ObjectMapper om = new ObjectMapper(); // json-> class
            User user = om.readValue(request.getInputStream(), User.class); // json 데이타를 user 객체로 매핑
            System.out.println(user); // 매핑 잘됬는지 확인

            UsernamePasswordAuthenticationToken authenticationToken = //인증 토큰 생성
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            //토큰 등록 후 PrincipalDetailsService 의 loadUserByUsername() 함수가 실행됨
            Authentication authentication = // 인증매니저에 인증 토큰등록
                    authenticationManager.authenticate(authenticationToken);


            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal(); //부모에서 자식으로 다운캐스팅
            System.out.println("로그인 완료됨:"+principalDetails.getUser().getUsername()); // 로그인이 되었다는 뜻.
            //authentication 객체가 session영역에 저장을 해야하고 그방법이 return 해주는것
            //리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는거임.
            //굳이 JWT 토큰을 사용하면서 세션만들 이유가 없음. 근데 단지 권한 처리때문에 session 넣어 줍니다.

            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨: 인증완료");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();  //부모에서 자식으로 다운캐스팅

        //RSA 방식은 아니고 Hash암호방식
        String jwtToken = JWT.create() // JWT 토큰생성
                .withSubject("cos토큰") // JWT 토큰별명
                        .withExpiresAt(new Date(System.currentTimeMillis()+(60000*30))) // 토큰 기한
                                .withClaim("id",principalDetails.getUser().getId()) // Claim id 등록
                                        .withClaim("username", principalDetails.getUser().getUsername()) // Claim username 등록
                                                .sign(Algorithm.HMAC512("cos")); //HMAC512 로 암호화 with 시크릿키

        response.addHeader("Authorization", "Bearer "+jwtToken); // JWT 토큰 응답

    }
}
