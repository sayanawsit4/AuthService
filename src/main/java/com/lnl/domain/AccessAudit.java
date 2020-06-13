package com.lnl.domain;

import lombok.Data;

import javax.persistence.*;
import java.util.UUID;

@Entity
@Data
@Table(name = "access_audit", schema = "lnlauth2")
public class AccessAudit {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    //this annontation has been removed to make domain classes compatiblity with various datasource
    //For postgres specific an implicit Java UUID to postgres UUID occurs in com.lnl.config.utils.UuidConverter
    //@org.hibernate.annotations.Type(type="pg-uuid")
    @Column(name = "access_audit_rec_no")
    private UUID acsAuditNo;

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "status")
    private String status;

    @Column(name = "no_of_attemps")
    private Integer noOfAttempts;

}
