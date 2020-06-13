package com.lnl.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.hibernate.annotations.Type;

import javax.persistence.*;

@Entity
@AllArgsConstructor
@Data
@Table(name = "oauth_code", schema = "lnlauth2")
public class OAuthCode {

    @Id
    @Column(name = "code")
    private String code;

    @Lob
    @Type(type = "org.hibernate.type.BinaryType")
    @Column(name = "authentication")
    private byte[] authentication;

}
