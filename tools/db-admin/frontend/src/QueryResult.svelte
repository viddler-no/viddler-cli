<script>
    export let result;
    function selectRow(event) {
        console.log(event);
    }
</script>
<style>
    table {
        border-collapse: collapse;
    }
    th {
        text-align: left;
    }
    th, td {
        border: 1px solid #eee;
        padding: 5px;
    }
    tbody tr:nth-child(even) {
        background-color: #fafffc;
    }
    tbody tr:hover {
        background-color: #fff0c0;
    }
    tbody tr.selected {
        background-color: #fff0c0;
    }
    td {
        vertical-align: top;
    }
</style>
<table>
    <thead>
        <tr>
            {#each result.columns as column}
                <th>{column}</th>
            {/each}
        </tr>
    </thead>
    <tbody>
        {#each result.rows as row}
            <tr on:click={selectRow}>
                {#each row as value}
                    <td>
                        {#if value.hasOwnProperty('Bytes')}
                            {value.Bytes}
                        {/if}
                    </td>
                {/each}
            </tr>
        {/each}
    </tbody>
</table>