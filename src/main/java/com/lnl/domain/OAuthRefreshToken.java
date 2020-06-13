package com.lnl.domain;

import lombok.Data;
import org.hibernate.annotations.Type;

import javax.persistence.*;

@Entity
@Data
@Table(name = "oauth_refresh_token", schema = "lnlauth2")
public class OAuthRefreshToken {

    @Id
    @Column(name = "token_id")
    private String tokenId;

    @Lob
    @Type(type = "org.hibernate.type.BinaryType")
    @Column(name = "token")
    private byte[] token;

    @Lob
    @Type(type = "org.hibernate.type.BinaryType")
    @Column(name = "authentication")
    private byte[] authentication;
}
