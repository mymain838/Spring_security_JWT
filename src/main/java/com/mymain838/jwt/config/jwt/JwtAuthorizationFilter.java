package com.mymain838.jwt.config.jwt;

//시큐리티가 filter가지고 있는데 그 필터중에 BasicAuthenticationFilter 라는 것이 있음.
//권한이나 인증이 필요한 특정 주소를 요청했을때 위 필터를 무조건 타게 되어있음.
//만약에 권한이 인증이 필요한 주소가 아니라면 이 필터를 안탐

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.mymain838.jwt.config.auth.PrincipalDetails;
import com.mymain838.jwt.model.User;
import com.mymain838.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager); // 매니저 등록
        this.userRepository = userRepository; // 유저 레포지토리 등록

    }
    //인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게 됨(doFilterInternal 함수)
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        System.out.println("인증이나 권한이 필요한 주소 요청이 됨.");

        String jwtHeader = request.getHeader("Authorization"); // Authorization 값
        System.out.println("jwtHeader : " + jwtHeader); //확인

        //JWT 토큰형식헤더를 가지고 있는지 확인
        if(jwtHeader ==null || !jwtHeader.startsWith("Bearer ")){ //없으면
            chain.doFilter(request, response); // 권한 없음
            return; //반환
        }
        //JWT 토큰을 검증을 해서 정상적인 사용자인지 확인
        String jwtToken = request.getHeader("Authorization").replace("Bearer ","");

        String username = JWT.require(Algorithm.HMAC512("cos"))
                .build().verify(jwtToken).getClaim("username").asString(); //사용자 인증
        //서명이 정상적으로 됬다면
        if(username != null){
         User userEntity = userRepository.findByUsername(username);
            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            //Jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
            //강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

        }

        chain.doFilter(request,response); //정상 처리
    }
}
