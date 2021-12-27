package com.tienngay.momopayment.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;

import java.util.Optional;

@NoRepositoryBean
public interface BaseRepository<T, ID> extends JpaRepository<T, ID> {

    @Override
    Optional<T> findById(ID id);

    @Override
    void deleteById(ID id);
}
