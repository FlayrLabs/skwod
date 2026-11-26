//! The two migration folders describe ONE schema: the server's SQL is the same on both
//! databases, so a migration written for one of them only breaks every host on the other.

use std::collections::BTreeMap;

/// What is in the schema: (table, column) → the kind of value it holds and whether it may be NULL.
type Schema = BTreeMap<(String, String), (&'static str, bool)>;

fn files(m: &sqlx::migrate::Migrator) -> Vec<(i64, String)> {
    m.iter().map(|m| (m.version, m.description.to_string())).collect()
}

/// Needs no database, so it runs everywhere: the same migrations are in both folders, and every
/// column one of them adds is added by its counterpart.
#[test]
fn both_migration_folders_carry_the_same_migrations() {
    let (sqlite, postgres) = (sqlx::migrate!("./migrations"), sqlx::migrate!("./migrations-postgres"));
    assert_eq!(files(&sqlite), files(&postgres), "a migration exists for one database only");
    // (Up to 18 some rebuild a table on SQLite where PostgreSQL alters it: the test below compares
    // what they end in. One written that way from here on needs an exception here.)
    for (s, p) in sqlite.iter().zip(postgres.iter()).filter(|(s, _)| s.version > 18) {
        assert_eq!(added(&s.sql), added(&p.sql), "migration {} adds different columns on the two databases", s.version);
    }
}

/// The `(table, column)`s a migration adds with `ALTER TABLE … ADD COLUMN`.
fn added(sql: &str) -> std::collections::BTreeSet<(String, String)> {
    let sql: String = sql.lines().map(|l| l.split("--").next().unwrap_or("")).collect::<Vec<_>>().join(" ");
    let words: Vec<String> = sql.split_whitespace().map(|w| w.trim_matches(|c| c == ';' || c == ',').to_ascii_lowercase()).collect();
    let mut out = std::collections::BTreeSet::new();
    let mut table = String::new();
    for (i, w) in words.iter().enumerate() {
        let next = |n: usize| words.get(i + n).cloned().unwrap_or_default();
        if w == "alter" && next(1) == "table" {
            table = next(2);
        } else if w == "add" && next(1) == "column" {
            out.insert((table.clone(), next(2)));
        }
    }
    out
}

/// The real thing: both folders applied to a real database of their kind end in the same tables
/// and columns. The PostgreSQL half needs `SKWOD_TEST_POSTGRES` (see `tests.rs`).
#[tokio::test]
async fn both_migration_folders_end_in_the_same_schema() {
    sqlx::any::install_default_drivers();
    let sqlite = sqlite_schema().await;
    assert!(sqlite.contains_key(&("sessions".into(), "token_hash".into())) && sqlite.len() > 300, "the schema was read: {}", sqlite.len());
    let Ok(admin) = std::env::var("SKWOD_TEST_POSTGRES") else {
        eprintln!("SKIPPED on SQLite alone: the PostgreSQL schema needs SKWOD_TEST_POSTGRES");
        return;
    };
    let postgres = postgres_schema(&admin).await;
    let only_sqlite: Vec<_> = sqlite.iter().filter(|(k, v)| postgres.get(k) != Some(v)).collect();
    let only_postgres: Vec<_> = postgres.iter().filter(|(k, v)| sqlite.get(k) != Some(v)).collect();
    assert!(only_sqlite.is_empty() && only_postgres.is_empty(), "SQLite has {only_sqlite:#?}\nPostgreSQL has {only_postgres:#?}");
}

async fn sqlite_schema() -> Schema {
    let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let rows: Vec<(String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT m.name, c.name, c.type, c.\"notnull\", c.pk FROM sqlite_master m JOIN pragma_table_info(m.name) c
          WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%' AND m.name <> '_sqlx_migrations'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    rows.into_iter().map(|(t, c, ty, notnull, pk)| ((t, c), (kind(&ty), notnull == 0 && pk == 0))).collect()
}

async fn postgres_schema(admin: &str) -> Schema {
    let pool = crate::tests::postgres_pool(admin).await;
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT table_name::text, column_name::text, data_type::text, is_nullable::text FROM information_schema.columns
          WHERE table_schema = 'public' AND table_name <> '_sqlx_migrations'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    rows.into_iter().map(|(t, c, ty, nullable)| ((t, c), (kind(&ty), nullable == "YES"))).collect()
}

fn kind(ty: &str) -> &'static str {
    match ty.to_ascii_lowercase().as_str() {
        "blob" | "bytea" => "bytes",
        "text" => "text",
        t if t.contains("int") => "integer",
        "real" | "double precision" => "real",
        other => panic!("a column type this test does not know: {other}"),
    }
}
