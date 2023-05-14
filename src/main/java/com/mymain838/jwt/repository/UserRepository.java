package com.mymain838.jwt.repository;

import com.mymain838.jwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


public interface UserRepository extends JpaRepository<User, Integer> {

    public User findByUsername(String username);
}
