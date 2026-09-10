package com.arshad.notes.security.token.repository;

import com.arshad.notes.security.token.entity.RefreshTokenFamily;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenFamilyRepository extends JpaRepository<RefreshTokenFamily, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select f from RefreshTokenFamily f where f.id = :id")
    Optional<RefreshTokenFamily> findLockedById(@Param("id") UUID id);

    @Modifying
    @Query(value = """
            DELETE FROM refresh_token_families WHERE id IN (
                SELECT id FROM refresh_token_families WHERE expires_at <= :now
                ORDER BY expires_at LIMIT :batchSize FOR UPDATE SKIP LOCKED
            )
            """, nativeQuery = true)
    int deleteExpiredBatch(@Param("now") Instant now, @Param("batchSize") int batchSize);
}
