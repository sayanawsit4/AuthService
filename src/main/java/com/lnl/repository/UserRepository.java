package com.lnl.repository;

import com.lnl.domain.User;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Transactional
public interface UserRepository extends JpaRepository<User, String> {

    //just a cache test.We need a centralised cache as redis
    @Query
    //@Cacheable(value = "byEmailId", key = "#email",condition = "#email != null")
    User findByEmail(String email);

    //@Cacheable("byEmailId")
    List<User> findAll();

    @Override
    //@CacheEvict(value = "cacheName", allEntries = true)
    //@CachePut(value = "byEmailId", key = "#p0.email")
    User save(User entity);

    @Override
    //@CacheEvict(value = "cacheName", allEntries = true)
    void delete(String name);
}
