package com.lnl.config.utils;

import com.sendgrid.*;

import java.io.IOException;

public class sendGridChecker {
    public static void main(String[] args) throws IOException {
        Email from = new Email("sayannayas@gmail.com");
        String subject = "Sending with Twilio SendGrid is Fun";
        Email to = new Email("sayannayas@gmail.com");
        Content content = new Content("text/plain", "and easy to do anywhere, even with Java");
        Mail mail = new Mail(from, subject, to, content);

        SendGrid sg = new SendGrid(System.getenv("SENDGRID_API_KEY"));
        System.out.println("erert"+System.getenv("SENDGRID_API_KEY"));
        Request request = new Request();
        try {
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody(mail.build());
            Response response = sg.api(request);
            System.out.println(response.getStatusCode());
            System.out.println(response.getBody());
            System.out.println(response.getHeaders());
        } catch (IOException ex) {
            throw ex;
        }
    }
}
