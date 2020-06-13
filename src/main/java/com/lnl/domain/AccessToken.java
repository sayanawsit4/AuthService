package com.lnl.domain;

import lombok.Data;
import org.hibernate.annotations.Type;

import javax.persistence.*;
import java.util.Date;

@Entity
@Data
@Table(name = "oauth_access_token", schema = "lnlauth2")
public class AccessToken {

    @Id
    @Column(name = "token_id")
    private String tokenId;

    @Column(name = "authentication_id")
    private String authenticationId;

    @Column(name = "user_name")
    private String userName;

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "refresh_token")
    private String refreshToken;

    @Column(name = "expiration")
    @Temporal(TemporalType.TIMESTAMP)
    private Date expiration;

    //for blob type data if we enable hbm ddl auto creation true,then type declaration is must
    // otherwise postgres does a default conversion to oid
    @Lob
    @Type(type = "org.hibernate.type.BinaryType")
    @Column(name = "token")
    private byte[] token;

    @Lob
    @Type(type = "org.hibernate.type.BinaryType")
    @Column(name = "authentication")
    private byte[] authentication;

}