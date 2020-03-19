import Head from 'next/head';

export default function Index() {
    return (
        <div>
            <Head>
                <title>Viddler - Videokonferanse for alle</title>
                <meta name="viewport" content="initial-scale=1.0, width=device-width" />
                <link href="https://fonts.googleapis.com/css2?family=Baloo+2:wght@400;700;800&display=swap" rel="stylesheet"/>
            </Head>
            <header>
                <h1>Videokonferanse for alle</h1>
                <ul>
                    <li>Enkelt å koble seg sammen</li>
                    <li>Del skjerm</li>
                    <li>Samhandle på dokument</li>
                </ul>
            </header>
            <div>
                <a className="start-link" href="/m/">&gt;</a>
            </div>
            <style jsx>{`
                @media only screen and (max-width: 600px) {
                    :global(html) {
                        font-size: 7px;
                    }
                }
                header {
                    padding: 8rem 7rem;
                    background: #fffde9;
                }
                h1 {
                    color: #3a381f;
                    font-family: 'Baloo 2';
                    font-size: 3.6rem;
                    font-weight: normal;
                    display: inline-block;
                    margin: 0 0 0.8rem;
                    line-height: 1;
                    border-bottom: 4px solid #f9f7db;
                }
                ul {
                    padding-left: 1.8rem;
                }
                li {
                    color: #3a381f;
                    font-family: 'Baloo 2';
                    font-size: 20px;
                    font-weight: normal;
                    line-height: 1.3;
                    margin-left: 0.2rem;
                }
                a.start-link {
                    display: inline-block;
                    width: 16rem;
                    height: 16rem;
                    font-family: 'Baloo 2';
                    font-size: 10rem;
                    color: #fffee9;
                    text-align: center;
                    text-decoration: none;
                    border-radius: 50%;
                    background: #c9c2f3;
                    margin: -5rem 0 0 17rem;
                }
                :global(body) {
                    margin: 0;
                }
            `}</style>
        </div>
    );
}