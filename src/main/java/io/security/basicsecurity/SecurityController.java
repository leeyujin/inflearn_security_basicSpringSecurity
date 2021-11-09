package io.security.basicsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(HttpSession session){
        // session에서 꺼내온 인증객체와,ContextHolder에서 꺼내온 방식의 인증객체는 동일함
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication1 = context.getAuthentication();
        return "home";
    }


    // SecurityContext 객체저장방식인 MODE_THREADLOCAL(default) 상태에서는 각 쓰레드별 ThreadLocal을 별도로 가지기 때문에 Main,자식 Thread간 인증정보는 다름
    // 인증 Filter가 메인 쓰레드로컬에 인증객체를 담음 -> 자식 쓰레드 인증 값과 다름
    @GetMapping("/thread")
    public String thread(){
        new Thread(() -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        }).start();
        return "thread";
    }


}
