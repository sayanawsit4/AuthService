package com.lnl.domain;

import lombok.AllArgsConstructor;
import lombok.Data;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

@Entity
@AllArgsConstructor
@Data
@Table(name = "oauth_approvals", schema = "lnlauth2")
public class OAuthApproval implements Serializable{

    @Id
    @Column(name = "userid")
    private String userId;

    @Id
    @Column(name = "clientid")
    private String clientId;

    @Id
    @Column(name = "scope")
    private String scope;

    @Column(name = "status")
    private String status;

    @Column(name = "expiresat")
    @Temporal(TemporalType.TIMESTAMP)
    private Date expiresat;

    @Column(name = "lastmodifiedat")
    @Temporal(TemporalType.TIMESTAMP)
    private Date lastmodifiedat;

}