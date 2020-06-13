package com.lnl.domain;

import lombok.AllArgsConstructor;
import lombok.Data;

import javax.persistence.*;
import java.util.Date;
import java.util.UUID;

@Entity
@AllArgsConstructor
@Data
@Table(name = "access_attempt_counter" ,schema = "lnlauth2")
public class AttemptCounter {

    @Id
    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "counter")
    private Integer counter;

    @Column(name = "last_attempt_time")
    @Temporal(TemporalType.TIMESTAMP)
    private Date lastAttempt;


}
