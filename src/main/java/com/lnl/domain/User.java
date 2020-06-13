package com.lnl.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.Email;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static com.google.common.collect.Sets.newHashSet;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
@Table(name = "user", schema = "lnlauth2")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "user_id")
    private UUID userId;

    @Size(min = 0, max = 500)
    private String password;

    @Email
    @Column(unique=true)
    @Size(min = 0, max = 50)
    private String email;

    private boolean activated = true;

    @Size(min = 0, max = 100)
    @Column(name = "first_name")
    private String firstName;

    @Size(min = 0, max = 100)
    @Column(name = "last_name")
    private String lastName;

    @Version //maintain version to get optimistic locking from JPA
    @Column(name = "version", columnDefinition = "integer DEFAULT 0", nullable = false)
    private Integer version = 0;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_authority",
               joinColumns = @JoinColumn(name = "user_id"),
               inverseJoinColumns = @JoinColumn(name = "authority"),
               uniqueConstraints = {@UniqueConstraint(
                    columnNames = {"user_id", "authority"})})
    private Set<Authority> authorities;
}