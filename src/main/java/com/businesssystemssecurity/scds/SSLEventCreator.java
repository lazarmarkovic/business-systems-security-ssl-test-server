package com.businesssystemssecurity.scds;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Configuration
@EnableScheduling
@Component
@EnableAsync
public class SSLEventCreator {

    @Autowired
    private RestTemplate restTemplate;

    @Async
    @Scheduled(fixedDelay = 1000 * 7)
    public void create() {
        try {
            String responseFromSub = restTemplate.getForObject("https://localhost:8443/api/testSSL/receiveFromThePKIServer", String.class);
            System.out.println("----> Response from sub: " + responseFromSub);
        } catch (Exception e) {
            //e.printStackTrace();
            System.out.println("Fatal error.");
        }
    }

//   @EventListener
//    public void onApplicationEvent(ContextRefreshedEvent event) {
//        try {
//            String responseFromSub = restTemplate.getForObject("https://localhost:8443/api/testSSL/receiveFromThePKIServer", String.class);
//            System.out.println("----> Response from sub: " + responseFromSub);
//        } catch (Exception e) {
//            //e.printStackTrace();
//            System.out.println("Fatal error.");
//        }
//    }
}