<script>
	import TableExplorer from './TableExplorer.svelte';
	export let structure;
</script>

<style>
</style>

{#each Object.entries(structure.table_defs) as [tablename, table]}
    <TableExplorer table={table}/>
{/each}