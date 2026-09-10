package com.arshad.notes.security.token.repository;

import com.arshad.notes.security.token.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    @Query("select t.family.id from RefreshToken t where t.tokenHash = :hash")
    Optional<UUID> findFamilyIdByTokenHash(@Param("hash") String hash);
}
