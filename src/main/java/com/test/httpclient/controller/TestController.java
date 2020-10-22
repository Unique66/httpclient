package com.test.httpclient.controller;

import com.test.httpclient.model.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class TestController {

    @GetMapping(value = "/user/{userName}")
    @ResponseBody
    public void demo(@PathVariable String userName) {
        System.out.println("qqq" + userName);
        return;
    }

    @RequestMapping(value="/user", method = RequestMethod.GET)
    @ResponseBody
    public String demo1() {
        System.out.println("hhh");
        return "hh";
    }

    @PostMapping(value = "/adduser")
    @ResponseBody
    public User demo2(@RequestBody User user) {
        System.out.println("userName:" + user.getName());
        System.out.println("nickName" + user.getNickName());
        return user;
    }
}
