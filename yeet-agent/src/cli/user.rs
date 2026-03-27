use clap::{Args, Subcommand};

use colored::Colorize as _;
use log::info;
use rootcause::Report;

use crate::{
    cli::common,
    cli_args::Config,
    section::{self, DisplaySectionItem},
    sig::ssh,
};

#[derive(Args)]
pub struct UserArgs {
    #[command(subcommand)]
    pub command: UserCommands,
}

#[derive(Subcommand)]
pub enum UserCommands {
    /// Create a new user (requires `all_tag`)
    Create,
    /// Delete an existing user (requires `all_tag`)
    Delete,
    /// Rename an existing user (requires `all_tag`)
    Rename,
}

pub async fn handle_user_command(args: UserArgs, config: &Config) -> Result<(), rootcause::Report> {
    match args.command {
        UserCommands::Create => create_user(config).await,
        UserCommands::Delete => delete_user(config).await,
        UserCommands::Rename => rename_user(config).await,
    }
}

async fn create_user(config: &Config) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let key = &ssh::key_by_url(&url)?;

    let level = inquire::Select::new(
        "What authorization level should the user receive?",
        vec![
            api::AuthLevel::Build,
            api::AuthLevel::Osquery,
            api::AuthLevel::Admin,
        ],
    )
    .prompt()?;

    let username = inquire::Text::new("What should the user be called?").prompt()?;

    let all_tag = inquire::Confirm::new("Should the user be a superuser (all_tag)?")
        .with_default(false)
        .prompt()?;

    let pub_key = ssh::get_pub_key_manual()?;

    api::create_user(
        &url,
        key,
        api::CreateUser {
            key: pub_key,
            level,
            username,
            all_tag,
        },
    )
    .await?;

    Ok(())
}

async fn delete_user(config: &Config) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let key = &ssh::key_by_url(&url)?;

    let user = inquire::Select::new(
        "Which user do you want to delete?",
        api::list_users(&url, key).await?,
    )
    .prompt()?;

    let confirm = inquire::Confirm::new(
        &format!(
            "Are you sure you want to delete {}. It will delete every trace of this user.
This action is not reversable",
            user.username
        )
        .red(),
    )
    .with_default(false)
    .prompt()?;

    if !confirm {
        info!("Aborting");
        return Ok(());
    }

    api::delete_key(&url, key, user.key).await?;
    info!("Deleted {user}");

    Ok(())
}

async fn rename_user(config: &Config) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let key = &ssh::key_by_url(&url)?;

    let user = inquire::Select::new(
        "Which user do you want to rename?",
        api::list_users(&url, key).await?,
    )
    .prompt()?;

    let new = inquire::Text::new(&format!("How should {} be called?", user.username)).prompt()?;

    api::rename_user(&url, key, user.id, &new).await?;

    info!("Renamed {} to {new}", user.username);

    Ok(())
}

pub async fn list_users(config: &Config) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let key = &ssh::key_by_url(&url)?;

    let users = {
        let users = api::list_users(&url, key).await?;
        users
            .into_iter()
            .map(|user| user.as_section_item())
            .collect()
    };

    let section = vec![("Users:".underline().to_string(), users)];
    section::print_sections(&section);

    Ok(())
}
