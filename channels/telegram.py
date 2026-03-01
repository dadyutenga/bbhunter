"""Telegram gateway for BBHunter agent mode (optional dependency)."""

from agent.loop import run_agent
from config.config import load_config


def run_telegram_bot(token: str):
    """
    Start Telegram bot polling.
    Requires optional dependency: python-telegram-bot
    """
    try:
        from telegram import Update
        from telegram.ext import (
            ApplicationBuilder,
            CommandHandler,
            ContextTypes,
            MessageHandler,
            filters,
        )
    except Exception as ex:
        raise RuntimeError(
            "Missing optional dependency 'python-telegram-bot'. "
            "Install with: pip install python-telegram-bot"
        ) from ex

    cfg = load_config()
    allowed_users = set(str(x) for x in cfg.get("telegram", {}).get("allowed_users", []))

    async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(
            "BBHunter AI ready.\n"
            "Send a domain, URL, or bug bounty task."
        )

    async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = str(update.effective_user.id)
        if allowed_users and user_id not in allowed_users:
            await update.message.reply_text("Unauthorized.")
            return

        user_input = update.message.text or ""
        session_id = f"tg_{user_id}"
        await update.message.reply_text("Processing...")
        try:
            response = run_agent(user_input, session_id, verbose=False)
        except Exception as ex:
            await update.message.reply_text(f"Error: {ex}")
            return

        if len(response) <= 4096:
            await update.message.reply_text(response)
            return

        for i in range(0, len(response), 4096):
            await update.message.reply_text(response[i : i + 4096])

    app = ApplicationBuilder().token(token).build()
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    print("BBHunter Telegram bot started.")
    app.run_polling()

