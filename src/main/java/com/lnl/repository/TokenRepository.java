package com.lnl.repository;

import com.lnl.domain.AccessToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

@Transactional
public interface TokenRepository extends JpaRepository<AccessToken, Long> {

    @Modifying
    @Query("delete from AccessToken t where t.expiration <= ?1")
    void deleteAllExpiredSince(Date now);

    @Query("select userName from AccessToken t where t.tokenId = ?1")
    String findUsernameByToken(String token);

}
