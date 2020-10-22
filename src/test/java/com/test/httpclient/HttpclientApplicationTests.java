package com.test.httpclient;

import com.alibaba.fastjson.JSON;
import com.test.httpclient.model.User;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.*;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@RunWith(SpringRunner.class)
@SpringBootTest
public class HttpclientApplicationTests {

    @Test
    public void contextLoads() {
//        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
//        params.add("userName", "xiaowang");
//        params.add("nickName", "tianmaojingling");
//        sendPostRequest("http://localhost:8080/adduser", params);
        User user = new User();
        user.setName("wangwu");
        user.setNickName("lisi");
        System.out.println(JSON.toJSON(user).toString());
    }
    public static void sendPostRequest(String url, MultiValueMap<String, String> params){
        RestTemplate client = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        HttpMethod method = HttpMethod.POST;
        // 以表单的方式提交
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        //将请求头部和参数合成一个请求
        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(params, headers);
        //执行HTTP请求，将返回的结构使用ResultVO类格式化
//        ResponseEntity<JSONObject> exchange = client.exchange(url, method, requestEntity, JSONObject.class);
        JSONObject jsonObject = client.postForObject(url, requestEntity, JSONObject.class);
        System.out.println("_______________");
        System.out.println(jsonObject.toString());
//        return response.getBody();
    }
}
