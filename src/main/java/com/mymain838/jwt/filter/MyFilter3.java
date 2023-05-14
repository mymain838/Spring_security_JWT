package com.mymain838.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;

        //토큰 : cos 이걸 만들어줘야 함 id,pw 정상적으로 들어와서
        // 로그인이 완료 되면 토큰을 만들어주고 그걸 응답을 해준다.
        //요청할 때 마다 header에 Authorization에 value 값으로
        // 토큰을 가지고 오니까 그때 토큰이 넘어오면 이 토큰이 내가만든
        //토큰이 맞는지만 검증 하면 됨.(RSA, HS256)
        if(req.getMethod().equals("POST")){ // 요청 방식 이 POST면
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Authorization"); // 헤더 "Autorization" 정보 조회
            System.out.println(headerAuth);
            System.out.println("필터3");
            if(headerAuth.equals("cos")){ // "Autorization" 값이 "cos" 이면?
                filterChain.doFilter(req, res); // 정상 접근
            }else{ // 아니면
                PrintWriter out = res.getWriter(); // 인증안됌 출력
                out.println("인증안됌");
            }
        }

    }
}
