# Executar aplicação
if __name__ == "__main__":
    import uvicorn

    # O bind em todas as interfaces é necessário para o encaminhamento Docker.
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)  # nosec B104
