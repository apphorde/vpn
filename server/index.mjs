import { readFile } from "fs/promises";
import { join } from "path";

async function load() {
  const db = process.env.DB_URL;
  const dataPath = join(process.cwd(), "data");
  const indexPage = await readFile("./client/index.html");
  const app = await readFile("./client/index.js");
  return {
    db: await import(db),
    app,
    dataPath,
    indexPage,
  };
}

async function main() {
  const { db, indexPage, app } = await load();
  const server = createServer(function (request, response) {
    const url = new URL(request.url);
    const route = `${request.method} ${url.pathname}`;

    switch (route) {
      case "GET /":
        return response.end(indexPage);

      case "GET /index.js":
        return response.end(app);

      case "GET /server":
        return response.end("OK");

      default:
        response.writeHead(404);
        response.end();
        return;
    }
  });

  server.listen(Number(process.env.PORT), function () {
    console.log("Server started at :" + process.env.PORT);
  });
}

main();
